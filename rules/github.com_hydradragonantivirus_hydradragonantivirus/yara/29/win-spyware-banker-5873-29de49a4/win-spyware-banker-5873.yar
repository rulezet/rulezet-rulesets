rule Win_Spyware_Banker_5873
{
strings:
	$a0 = { 1baf6aa260ebc85dfcf7a1733d3f778bf4b8c676f1a75fac5ab47660e49434cb4d165c8f62fd89a5a036b035fbe4aa94d0826910772cfb3c5b9cd30225d2f7694859bec7 }


condition:
	$a0
}