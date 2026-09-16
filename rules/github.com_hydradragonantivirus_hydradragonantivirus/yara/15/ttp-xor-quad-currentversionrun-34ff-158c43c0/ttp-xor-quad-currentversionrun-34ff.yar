rule TTP_XOR_QUAD_CurrentVersionRun_34ff {
  strings:
    $key_34ff = { 67 90 [2] 43 9e [2] 68 b2 [2] 46 90 [2] 52 8b [2] 5d 91 [2] 43 8c [2] 41 8d [2] 5a 8b [2] 46 8c [2] 5a a3 }

  condition:
    any of them
}