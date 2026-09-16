rule TTP_XOR_WriteProcessMemory_921c {
  strings:
    $key_921c = { c5 6e [2] f7 4c [2] f1 79 [2] df 79 [2] e0 65 }

  condition:
    any of them
}