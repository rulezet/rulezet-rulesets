rule TTP_XOR_WriteProcessMemory_2cbd {
  strings:
    $key_2cbd = { 7b cf [2] 49 ed [2] 4f d8 [2] 61 d8 [2] 5e c4 }

  condition:
    any of them
}