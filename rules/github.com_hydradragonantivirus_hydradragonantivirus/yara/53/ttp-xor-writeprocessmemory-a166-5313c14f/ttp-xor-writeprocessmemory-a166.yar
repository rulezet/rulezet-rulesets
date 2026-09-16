rule TTP_XOR_WriteProcessMemory_a166 {
  strings:
    $key_a166 = { f6 14 [2] c4 36 [2] c2 03 [2] ec 03 [2] d3 1f }

  condition:
    any of them
}