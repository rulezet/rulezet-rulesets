rule TTP_XOR_WriteProcessMemory_669a {
  strings:
    $key_669a = { 31 e8 [2] 03 ca [2] 05 ff [2] 2b ff [2] 14 e3 }

  condition:
    any of them
}