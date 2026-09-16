rule TTP_XOR_WriteProcessMemory_921d {
  strings:
    $key_921d = { c5 6f [2] f7 4d [2] f1 78 [2] df 78 [2] e0 64 }

  condition:
    any of them
}