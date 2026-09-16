rule TTP_XOR_WriteProcessMemory_0cbf {
  strings:
    $key_0cbf = { 5b cd [2] 69 ef [2] 6f da [2] 41 da [2] 7e c6 }

  condition:
    any of them
}