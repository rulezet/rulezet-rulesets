rule TTP_XOR_QUAD_CurrentVersionRun_fee2 {
  strings:
    $key_fee2 = { ad 8d [2] 89 83 [2] a2 af [2] 8c 8d [2] 98 96 [2] 97 8c [2] 89 91 [2] 8b 90 [2] 90 96 [2] 8c 91 [2] 90 be }

  condition:
    any of them
}