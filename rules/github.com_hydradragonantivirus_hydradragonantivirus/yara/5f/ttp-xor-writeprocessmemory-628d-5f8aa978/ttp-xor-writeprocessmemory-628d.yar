rule TTP_XOR_WriteProcessMemory_628d {
  strings:
    $key_628d = { 35 ff [2] 07 dd [2] 01 e8 [2] 2f e8 [2] 10 f4 }

  condition:
    any of them
}