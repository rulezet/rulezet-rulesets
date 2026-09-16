rule TTP_XOR_WriteProcessMemory_3cbd {
  strings:
    $key_3cbd = { 6b cf [2] 59 ed [2] 5f d8 [2] 71 d8 [2] 4e c4 }

  condition:
    any of them
}