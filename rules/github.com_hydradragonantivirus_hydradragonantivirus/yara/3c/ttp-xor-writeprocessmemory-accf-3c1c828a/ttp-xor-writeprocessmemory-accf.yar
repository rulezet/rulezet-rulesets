rule TTP_XOR_WriteProcessMemory_accf {
  strings:
    $key_accf = { fb bd [2] c9 9f [2] cf aa [2] e1 aa [2] de b6 }

  condition:
    any of them
}