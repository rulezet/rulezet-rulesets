rule Windows_Trojan_BadIIS_56117744 {
    meta:
        author = "Elastic Security"
        id = "56117744-f09a-4efa-bfc6-0f2273e6025c"
        fingerprint = "d83da4a12e47bf898a4150b2c2c4c2815f9bcf59e48ea7cd416ff2a8382580ba"
        creation_date = "2026-01-26"
        last_modified = "2026-02-02"
        threat_name = "Windows.Trojan.BadIIS"
        reference_sample = "a69a5fe19eae825c463e83265f7bbe31d1e514176e11ba5f63c25351542c46b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "bing|google|naver" fullword
        $a2 = "bingbot|Googlebot|Yeti" fullword
        $a3 = "bingbot|Googlebot|coccocbot" fullword
        $a4 = "|split'.split('|'),0,{}))</script>\n" fullword
        $a5 = "iPhone|iPad|iPod|iOS|Android|uc|BlackBerry|HUAWEI" fullword
        $a6 = ".js|.css|.jpg|.jpeg|.png|.gif|.bmp|.ico|.svg|.tif|.pict|.tiff|.swf" fullword
        $a7 = "tee|pat|and|app|poker|gam|sto|vid|bea|slo|fis|bac|pac|tig|bmw|fru|bull|card|gods|fish|mahj" fullword
        $a8 = "return||if|replace|while||13|eval|toString|String||new||RegExp|script|window|document||write|type|text|javascript|src" fullword
    condition:
        4 of them
}