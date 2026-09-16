rule TTP_XOR_QUAD_CurrentVersionRun_2011 {
  strings:
    $key_2011 = { 73 7e [2] 57 70 [2] 7c 5c [2] 52 7e [2] 46 65 [2] 49 7f [2] 57 62 [2] 55 63 [2] 4e 65 [2] 52 62 [2] 4e 4d }

  condition:
    any of them
}