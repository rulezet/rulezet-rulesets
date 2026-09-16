rule TTP_XOR_WriteProcessMemory_cfbf {
  strings:
    $key_cfbf = { 98 cd [2] aa ef [2] ac da [2] 82 da [2] bd c6 }

  condition:
    any of them
}