rule TTP_XOR_QUAD_CurrentVersionRun_00ff {
  strings:
    $key_00ff = { 53 90 [2] 77 9e [2] 5c b2 [2] 72 90 [2] 66 8b [2] 69 91 [2] 77 8c [2] 75 8d [2] 6e 8b [2] 72 8c [2] 6e a3 }

  condition:
    any of them
}