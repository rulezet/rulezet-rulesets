rule TTP_XOR_QUAD_CurrentVersionRun_32e2 {
  strings:
    $key_32e2 = { 61 8d [2] 45 83 [2] 6e af [2] 40 8d [2] 54 96 [2] 5b 8c [2] 45 91 [2] 47 90 [2] 5c 96 [2] 40 91 [2] 5c be }

  condition:
    any of them
}