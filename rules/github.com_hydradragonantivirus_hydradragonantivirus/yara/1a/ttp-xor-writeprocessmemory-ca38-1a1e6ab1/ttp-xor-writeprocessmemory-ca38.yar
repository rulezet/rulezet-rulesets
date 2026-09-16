rule TTP_XOR_WriteProcessMemory_ca38 {
  strings:
    $key_ca38 = { 9d 4a [2] af 68 [2] a9 5d [2] 87 5d [2] b8 41 }

  condition:
    any of them
}