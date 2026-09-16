rule TTP_XOR_QUAD_CurrentVersionRun_150d {
  strings:
    $key_150d = { 46 62 [2] 62 6c [2] 49 40 [2] 67 62 [2] 73 79 [2] 7c 63 [2] 62 7e [2] 60 7f [2] 7b 79 [2] 67 7e [2] 7b 51 }

  condition:
    any of them
}