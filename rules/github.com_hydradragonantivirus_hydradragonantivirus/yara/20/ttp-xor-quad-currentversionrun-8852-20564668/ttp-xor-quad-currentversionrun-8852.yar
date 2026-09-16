rule TTP_XOR_QUAD_CurrentVersionRun_8852 {
  strings:
    $key_8852 = { db 3d [2] ff 33 [2] d4 1f [2] fa 3d [2] ee 26 [2] e1 3c [2] ff 21 [2] fd 20 [2] e6 26 [2] fa 21 [2] e6 0e }

  condition:
    any of them
}