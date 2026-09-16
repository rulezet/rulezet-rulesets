rule TTP_XOR_QUAD_CurrentVersionRun_20ff {
  strings:
    $key_20ff = { 73 90 [2] 57 9e [2] 7c b2 [2] 52 90 [2] 46 8b [2] 49 91 [2] 57 8c [2] 55 8d [2] 4e 8b [2] 52 8c [2] 4e a3 }

  condition:
    any of them
}