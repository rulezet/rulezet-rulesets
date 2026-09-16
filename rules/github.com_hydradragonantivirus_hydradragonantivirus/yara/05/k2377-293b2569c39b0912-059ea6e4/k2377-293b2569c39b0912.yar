rule k2377_293b2569c39b0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2377.293b2569c39b0912"
    cluster      = "k2377.293b2569c39b0912"
    cluster_size = "5"
    filetype     = "HTML document"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cryxos redirector redir"
    md5_hashes   = "['5883c9347ffd589f881e1726c462d98b','80f48f93f0d6e26779f634082c04263a','df25c6dd953797f1c780d70aa1f3ff92']"

  strings:
    $hex_string = "KQDJdAcXuamybjSwEPaDCMucVbAgIHBVksKLoeF|iframe|25px|ts|v_cd0f29d"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}