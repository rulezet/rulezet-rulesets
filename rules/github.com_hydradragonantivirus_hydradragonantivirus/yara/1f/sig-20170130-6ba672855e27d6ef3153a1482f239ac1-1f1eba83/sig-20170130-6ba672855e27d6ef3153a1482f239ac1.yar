rule sig_20170130_6ba672855e27d6ef3153a1482f239ac1 {
  meta:
    description = "datamaliciousorder - file 20170130_6ba672855e27d6ef3153a1482f239ac1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e5e92cdc148a762d992ad5323b87b358d61b570c7dc606823c3e70f3c09ebdf"

  strings:
    $s1  = "bcyluliqtasnymixziwwuvixijetqikidypiljoflunqinvycnoxzajenudgadgadqohbixinfohymhibicfugowaffecupychosxexuzvecyzbogyjuxraxtyrcutjo" ascii
    $s2  = "161omzops\", \"owq272lnerc\", \"ojd646eszyll\", [true, \"cmd\"], \"oxj377dpit\", true, \"ufz396ricru\", true][5][1] + [true, tru" ascii
    $s3  = "bcyluliqtasnymixziwwuvixijetqikidypiljoflunqinvycnoxzajenudgadgadqohbixinfohymhibicfugowaffecupychosxexuzvecyzbogyjuxraxtyrcutjo" ascii
    $s4  = "ittaqzafwirefzecnopexbexyzyxxitylaqagetkifikujxyryfybfigyqemyzzybebozuwxytwyzegyqilejoruhucizitgygfycekisukbijupvivtobqitivsufex" ascii
    $s5  = "bcyluliqtasnymixziwwuvixijetqikidypiljoflunqinvycnoxzajenudgadgadqohbixinfohymhibicfugowaffecupychosxexuzvecyzbogyjuxraxtyrcutjo" ascii
    $s6  = "bcyluliqtasnymixziwwuvixijetqikidypiljoflunqinvycnoxzajenudgadgadqohbixinfohymhibicfugowaffecupychosxexuzvecyzbogyjuxraxtyrcutjo" ascii
    $s7  = "amhallajuberwobxonorxibfihashycyjyflujewvosxidvazuhujuqovybjafvengejasawecpogebecivucihqyrgilgyhortetivyqpobgadqezafzanahicuwped" ascii
    $s8  = "kn\", \"yvap320acca\", true], \"if465anv\", true, \"dexwo584ecid\", true, true, \"oh195uznes\", \"pju885zys\"][2][0] + [true, \"" ascii
    $s9  = "if ([\"obo188rxi\", true, \"azqab796go\", \"hziza137ncedz\", true, true, \"smazhu907ykv\", true, new Function([true, \"alfy583od" ascii
    $s10 = "\", [\"le483si\", \"GET\", true], \"vyhme922kumga\", \"apy906vox\", \"nbo293lwaxl\", \"ijk421tu\", \"xjy608daf\"][4][1], [[\"any" ascii
    $s11 = "owacinavrowylqufijjaxibgujhojjuxuvhecinfygzurtyhexbasamytjisbizgabtoqcawzyfpacawiscubufuzepilehevexjyrqokquzyhxanoxtubahuqtulety" ascii
    $s12 = "bcyluliqtasnymixziwwuvixijetqikidypiljoflunqinvycnoxzajenudgadgadqohbixinfohymhibicfugowaffecupychosxexuzvecyzbogyjuxraxtyrcutjo" ascii
    $s13 = "bcyluliqtasnymixziwwuvixijetqikidypiljoflunqinvycnoxzajenudgadgadqohbixinfohymhibicfugowaffecupychosxexuzvecyzbogyjuxraxtyrcutjo" ascii
    $s14 = "ittaqzafwirefzecnopexbexyzyxxitylaqagetkifikujxyryfybfigyqemyzzybebozuwxytwyzegyqilejoruhucizitgygfycekisukbijupvivtobqitivsufex" ascii
    $s15 = ", true, true, true, \"emwivb664pded\"][4][0] + [\"gwotm307bijdi\", true, \"pa835qan\", \"ymfol696aqty\", [\"she\", true, true], " ascii
    $s16 = "\"], true, \"votf609tfetga\"][7][1] + [true, \"uxwo878da\", \"ckov730uzdo\", [\"eof\", \"xono157egby\", \"axevq509iheg\"], \"dut" ascii
    $s17 = "true, true, \"yrf566ifdex\", \"azf305ehby\", \"sy729maq\", \"kvi419ku\", true, true][0][1] + [\"ckypdy309omo\", true, \"ete630ok" ascii
    $s18 = "ue, \"ing\"], true][10][2] + [\"uwi777wa\", \"ugji416dgiwt\", true, [\"ynde459wo\", \".Fi\"], \"sziwmu928ezi\", true, \"ejibh608" ascii
    $s19 = "xy195ivoqw\", \"ygji528dyhx\", \"wojy383vrine\", \"lmemcu450mozw\", true, [\"ry \", true], \"edsuzf530yhi\", true, \"wda449elber" ascii
    $s20 = ", true, \"kijny240ixku\", \"ena314ecqoww\", \"yjhu777wu\", \"ugz691exso\", true, true, true][0][1] + [\"zna938abz\", \"ifba830gb" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}