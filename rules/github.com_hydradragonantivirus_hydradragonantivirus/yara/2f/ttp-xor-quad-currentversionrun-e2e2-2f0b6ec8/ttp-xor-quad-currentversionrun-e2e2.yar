rule TTP_XOR_QUAD_CurrentVersionRun_e2e2 {
  strings:
    $key_e2e2 = { b1 8d [2] 95 83 [2] be af [2] 90 8d [2] 84 96 [2] 8b 8c [2] 95 91 [2] 97 90 [2] 8c 96 [2] 90 91 [2] 8c be }

  condition:
    any of them
}