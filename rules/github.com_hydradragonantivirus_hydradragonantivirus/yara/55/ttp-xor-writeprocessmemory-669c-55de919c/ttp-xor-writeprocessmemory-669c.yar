rule TTP_XOR_WriteProcessMemory_669c {
  strings:
    $key_669c = { 31 ee [2] 03 cc [2] 05 f9 [2] 2b f9 [2] 14 e5 }

  condition:
    any of them
}