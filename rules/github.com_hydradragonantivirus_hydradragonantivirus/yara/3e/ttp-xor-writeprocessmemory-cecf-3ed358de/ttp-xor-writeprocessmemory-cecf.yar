rule TTP_XOR_WriteProcessMemory_cecf {
  strings:
    $key_cecf = { 99 bd [2] ab 9f [2] ad aa [2] 83 aa [2] bc b6 }

  condition:
    any of them
}