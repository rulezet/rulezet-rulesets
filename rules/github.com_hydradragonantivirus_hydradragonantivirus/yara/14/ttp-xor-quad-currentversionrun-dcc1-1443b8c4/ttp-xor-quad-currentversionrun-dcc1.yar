rule TTP_XOR_QUAD_CurrentVersionRun_dcc1 {
  strings:
    $key_dcc1 = { 8f ae [2] ab a0 [2] 80 8c [2] ae ae [2] ba b5 [2] b5 af [2] ab b2 [2] a9 b3 [2] b2 b5 [2] ae b2 [2] b2 9d }

  condition:
    any of them
}