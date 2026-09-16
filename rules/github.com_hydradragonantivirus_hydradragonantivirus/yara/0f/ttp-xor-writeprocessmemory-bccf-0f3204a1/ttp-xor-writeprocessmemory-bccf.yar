rule TTP_XOR_WriteProcessMemory_bccf {
  strings:
    $key_bccf = { eb bd [2] d9 9f [2] df aa [2] f1 aa [2] ce b6 }

  condition:
    any of them
}