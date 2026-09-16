rule TTP_XOR_QUAD_CurrentVersionRun_e5e2 {
  strings:
    $key_e5e2 = { b6 8d [2] 92 83 [2] b9 af [2] 97 8d [2] 83 96 [2] 8c 8c [2] 92 91 [2] 90 90 [2] 8b 96 [2] 97 91 [2] 8b be }

  condition:
    any of them
}