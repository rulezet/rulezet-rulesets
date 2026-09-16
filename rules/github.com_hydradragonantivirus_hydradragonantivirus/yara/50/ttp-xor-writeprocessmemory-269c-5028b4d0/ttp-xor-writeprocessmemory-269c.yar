rule TTP_XOR_WriteProcessMemory_269c {
  strings:
    $key_269c = { 71 ee [2] 43 cc [2] 45 f9 [2] 6b f9 [2] 54 e5 }

  condition:
    any of them
}