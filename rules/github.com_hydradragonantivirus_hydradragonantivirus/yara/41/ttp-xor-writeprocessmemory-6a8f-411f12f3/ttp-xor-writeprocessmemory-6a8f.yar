rule TTP_XOR_WriteProcessMemory_6a8f {
  strings:
    $key_6a8f = { 3d fd [2] 0f df [2] 09 ea [2] 27 ea [2] 18 f6 }

  condition:
    any of them
}