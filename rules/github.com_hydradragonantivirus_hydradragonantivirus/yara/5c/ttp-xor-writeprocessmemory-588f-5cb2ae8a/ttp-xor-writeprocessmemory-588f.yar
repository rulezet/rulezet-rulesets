rule TTP_XOR_WriteProcessMemory_588f {
  strings:
    $key_588f = { 0f fd [2] 3d df [2] 3b ea [2] 15 ea [2] 2a f6 }

  condition:
    any of them
}