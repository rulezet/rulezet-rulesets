rule TTP_XOR_WriteProcessMemory_bc9d {
  strings:
    $key_bc9d = { eb ef [2] d9 cd [2] df f8 [2] f1 f8 [2] ce e4 }

  condition:
    any of them
}