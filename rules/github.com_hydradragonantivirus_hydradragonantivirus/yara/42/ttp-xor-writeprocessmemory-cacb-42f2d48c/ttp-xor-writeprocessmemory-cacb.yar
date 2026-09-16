rule TTP_XOR_WriteProcessMemory_cacb {
  strings:
    $key_cacb = { 9d b9 [2] af 9b [2] a9 ae [2] 87 ae [2] b8 b2 }

  condition:
    any of them
}