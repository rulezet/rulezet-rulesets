rule TTP_XOR_WriteProcessMemory_6cbf {
  strings:
    $key_6cbf = { 3b cd [2] 09 ef [2] 0f da [2] 21 da [2] 1e c6 }

  condition:
    any of them
}