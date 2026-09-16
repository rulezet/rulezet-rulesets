rule TTP_XOR_WriteProcessMemory_ddae {
  strings:
    $key_ddae = { 8a dc [2] b8 fe [2] be cb [2] 90 cb [2] af d7 }

  condition:
    any of them
}