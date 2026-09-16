rule TTP_XOR_WriteProcessMemory_9ca9 {
  strings:
    $key_9ca9 = { cb db [2] f9 f9 [2] ff cc [2] d1 cc [2] ee d0 }

  condition:
    any of them
}