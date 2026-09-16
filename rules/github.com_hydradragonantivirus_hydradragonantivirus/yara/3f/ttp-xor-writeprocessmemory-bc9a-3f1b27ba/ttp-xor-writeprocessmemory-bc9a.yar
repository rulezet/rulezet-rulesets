rule TTP_XOR_WriteProcessMemory_bc9a {
  strings:
    $key_bc9a = { eb e8 [2] d9 ca [2] df ff [2] f1 ff [2] ce e3 }

  condition:
    any of them
}