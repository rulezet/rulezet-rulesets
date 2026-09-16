rule TTP_XOR_QUAD_CurrentVersionRun_19e2 {
  strings:
    $key_19e2 = { 4a 8d [2] 6e 83 [2] 45 af [2] 6b 8d [2] 7f 96 [2] 70 8c [2] 6e 91 [2] 6c 90 [2] 77 96 [2] 6b 91 [2] 77 be }

  condition:
    any of them
}