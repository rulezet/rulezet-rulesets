rule TTP_XOR_WriteProcessMemory_b8d8 {
  strings:
    $key_b8d8 = { ef aa [2] dd 88 [2] db bd [2] f5 bd [2] ca a1 }

  condition:
    any of them
}