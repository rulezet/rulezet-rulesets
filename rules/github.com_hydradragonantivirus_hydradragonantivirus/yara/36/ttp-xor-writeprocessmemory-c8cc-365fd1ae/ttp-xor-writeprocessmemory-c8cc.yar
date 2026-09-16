rule TTP_XOR_WriteProcessMemory_c8cc {
  strings:
    $key_c8cc = { 9f be [2] ad 9c [2] ab a9 [2] 85 a9 [2] ba b5 }

  condition:
    any of them
}