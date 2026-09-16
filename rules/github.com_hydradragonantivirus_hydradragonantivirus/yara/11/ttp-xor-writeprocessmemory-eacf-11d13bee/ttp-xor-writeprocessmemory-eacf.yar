rule TTP_XOR_WriteProcessMemory_eacf {
  strings:
    $key_eacf = { bd bd [2] 8f 9f [2] 89 aa [2] a7 aa [2] 98 b6 }

  condition:
    any of them
}