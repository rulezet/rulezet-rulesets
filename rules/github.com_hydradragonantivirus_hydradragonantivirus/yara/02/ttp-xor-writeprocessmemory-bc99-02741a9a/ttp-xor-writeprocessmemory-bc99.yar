rule TTP_XOR_WriteProcessMemory_bc99 {
  strings:
    $key_bc99 = { eb eb [2] d9 c9 [2] df fc [2] f1 fc [2] ce e0 }

  condition:
    any of them
}