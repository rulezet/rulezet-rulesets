rule TTP_XOR_QUAD_CurrentVersionRun_bdbc {
  strings:
    $key_bdbc = { ee d3 [2] ca dd [2] e1 f1 [2] cf d3 [2] db c8 [2] d4 d2 [2] ca cf [2] c8 ce [2] d3 c8 [2] cf cf [2] d3 e0 }

  condition:
    any of them
}