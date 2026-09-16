rule TTP_XOR_WriteProcessMemory_dcbf {
  strings:
    $key_dcbf = { 8b cd [2] b9 ef [2] bf da [2] 91 da [2] ae c6 }

  condition:
    any of them
}