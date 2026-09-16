rule TTP_XOR_WriteProcessMemory_258b {
  strings:
    $key_258b = { 72 f9 [2] 40 db [2] 46 ee [2] 68 ee [2] 57 f2 }

  condition:
    any of them
}