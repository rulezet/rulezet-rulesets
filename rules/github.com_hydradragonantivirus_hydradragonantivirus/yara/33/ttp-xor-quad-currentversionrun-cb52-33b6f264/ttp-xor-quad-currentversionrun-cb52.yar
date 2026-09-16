rule TTP_XOR_QUAD_CurrentVersionRun_cb52 {
  strings:
    $key_cb52 = { 98 3d [2] bc 33 [2] 97 1f [2] b9 3d [2] ad 26 [2] a2 3c [2] bc 21 [2] be 20 [2] a5 26 [2] b9 21 [2] a5 0e }

  condition:
    any of them
}