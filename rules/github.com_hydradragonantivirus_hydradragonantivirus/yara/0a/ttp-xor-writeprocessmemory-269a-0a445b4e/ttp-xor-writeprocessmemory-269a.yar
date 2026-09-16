rule TTP_XOR_WriteProcessMemory_269a {
  strings:
    $key_269a = { 71 e8 [2] 43 ca [2] 45 ff [2] 6b ff [2] 54 e3 }

  condition:
    any of them
}