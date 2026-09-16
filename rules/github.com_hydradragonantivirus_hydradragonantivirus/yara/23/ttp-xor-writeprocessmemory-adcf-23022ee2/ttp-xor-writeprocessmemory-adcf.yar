rule TTP_XOR_WriteProcessMemory_adcf {
  strings:
    $key_adcf = { fa bd [2] c8 9f [2] ce aa [2] e0 aa [2] df b6 }

  condition:
    any of them
}