rule TTP_XOR_QUAD_CurrentVersionRun_15ff {
  strings:
    $key_15ff = { 46 90 [2] 62 9e [2] 49 b2 [2] 67 90 [2] 73 8b [2] 7c 91 [2] 62 8c [2] 60 8d [2] 7b 8b [2] 67 8c [2] 7b a3 }

  condition:
    any of them
}