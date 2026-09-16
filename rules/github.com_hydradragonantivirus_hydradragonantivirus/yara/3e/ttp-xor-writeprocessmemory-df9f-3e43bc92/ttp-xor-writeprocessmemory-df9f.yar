rule TTP_XOR_WriteProcessMemory_df9f {
  strings:
    $key_df9f = { 88 ed [2] ba cf [2] bc fa [2] 92 fa [2] ad e6 }

  condition:
    any of them
}