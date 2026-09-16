rule Win_Trojan_Agent_32987
{
strings:
	$a0 = { c73e641117a301a8c76b75b10fc9b94e496cec0c77ad9089b10888e518880250baecfa6fcb5beca535d9d7eff2641f980c6f7e8fdef5b5f93091b92c6bdddcc1ff6cb21c4e8ad86b90e373bcf665 }


condition:
	$a0
}