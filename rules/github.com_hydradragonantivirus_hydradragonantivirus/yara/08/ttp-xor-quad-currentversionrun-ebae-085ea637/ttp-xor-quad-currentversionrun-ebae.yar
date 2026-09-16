rule TTP_XOR_QUAD_CurrentVersionRun_ebae {
  strings:
    $key_ebae = { b8 c1 [2] 9c cf [2] b7 e3 [2] 99 c1 [2] 8d da [2] 82 c0 [2] 9c dd [2] 9e dc [2] 85 da [2] 99 dd [2] 85 f2 }

  condition:
    any of them
}