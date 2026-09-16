rule TTP_XOR_WriteProcessMemory_fd88 {
  strings:
    $key_fd88 = { aa fa [2] 98 d8 [2] 9e ed [2] b0 ed [2] 8f f1 }

  condition:
    any of them
}